// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/store"
)

type mcpBGPRPKIPostureBackend struct{ server *Server }

func bgpRPKIPostureToolOption(server *Server) (mcp.Option, error) {
	schema, err := bgpHistoryToolSchema("/v1/bgp/visibility/{id}/rpki-posture", 4, "id", "context_id", "prefix_id")
	if err != nil {
		return nil, err
	}
	return mcp.WithBGPRPKIPostureBackend(mcpBGPRPKIPostureBackend{server}, schema), nil
}

func (b mcpBGPRPKIPostureBackend) BGPRPKIPosture(ctx context.Context, actor *auth.Principal, command mcp.BGPRPKIPostureCommand) (json.RawMessage, error) {
	if b.server == nil || b.server.pool == nil || actor == nil || actor.UserID == "" {
		return nil, apierror.Forbidden("a current authorized tenant user is required")
	}
	query := bgpRPKIPostureQuery{Monitor: command.ID, Context: command.ContextID, Prefix: command.PrefixID}
	if command.IntendedASN != nil {
		query.IntendedASN = *command.IntendedASN
	}
	at := time.Now().UTC()
	read := func(ctx context.Context) (json.RawMessage, error) {
		if err := mcp.CheckOriginatingCredential(ctx); err != nil {
			return nil, err
		}
		status, err := NewTenantStatusCache(b.server.pool, 0).TenantStatus(ctx, actor.TenantID)
		if err != nil {
			return nil, err
		}
		if status != "active" {
			return nil, apierror.Forbidden("RPKI posture tenant is inactive")
		}
		result, err := b.server.readBGPRPKIPosture(ctx, actor, query, at, true)
		if err != nil {
			return nil, bgpASPathHistoryError(err)
		}
		return marshalNativeBGPRPKIPosture(result)
	}
	body, err := read(ctx)
	if err != nil {
		return nil, err
	}
	if err := mcp.RetainNativePublication(ctx, func(active context.Context) error {
		latest, err := read(active)
		if err != nil {
			return err
		}
		if !bytes.Equal(body, latest) {
			return apierror.Conflict("RPKI posture changed before publication")
		}
		return active.Err()
	}, func() {}); err != nil {
		return nil, err
	}
	return body, nil
}

func marshalNativeBGPRPKIPosture(result bgpRPKICurrentPosture) (json.RawMessage, error) {
	type verdict struct {
		opendata.RPKIPosture
		ValidatorVersion mcp.NativeRoleDigest `json:"validator_version,omitempty"`
	}
	type incidentLink struct {
		store.BGPRPKIHijack
		IncidentID mcp.NativeRoleUUID `json:"incident_id"`
	}
	type path struct {
		bgpRPKIPathPosture
		RouterID       mcp.NativeRoleUUID   `json:"router_id"`
		Vantage        mcp.NativeRoleDigest `json:"vantage"`
		Generation     mcp.NativeRoleUUID   `json:"generation"`
		RPKI           verdict              `json:"rpki"`
		RelatedHijacks []incidentLink       `json:"related_hijacks,omitempty"`
	}
	type point struct {
		bgpRPKITrendPoint
		ID      mcp.NativeRoleUUID   `json:"id"`
		Vantage mcp.NativeRoleDigest `json:"vantage"`
		Posture verdict              `json:"posture"`
	}
	out := struct {
		bgpRPKICurrentPosture
		ContextID mcp.NativeRoleUUID `json:"context_id"`
		PrefixID  mcp.NativeRoleUUID `json:"prefix_id"`
		MonitorID mcp.NativeRoleUUID `json:"monitor_id"`
		Paths     []path             `json:"paths"`
		Trend     []point            `json:"trend"`
	}{bgpRPKICurrentPosture: result, ContextID: mcp.NativeRoleUUID(result.ContextID), PrefixID: mcp.NativeRoleUUID(result.PrefixID),
		MonitorID: mcp.NativeRoleUUID(result.MonitorID), Paths: []path{}, Trend: []point{}}
	for _, row := range result.Paths {
		v := path{bgpRPKIPathPosture: row, RouterID: mcp.NativeRoleUUID(row.RouterID), Vantage: mcp.NativeRoleDigest(row.Vantage),
			Generation: mcp.NativeRoleUUID(row.Generation), RPKI: verdict{row.RPKI, mcp.NativeRoleDigest(row.RPKI.ValidatorVersion)}}
		for _, link := range row.RelatedHijacks {
			v.RelatedHijacks = append(v.RelatedHijacks, incidentLink{link, mcp.NativeRoleUUID(link.IncidentID)})
		}
		out.Paths = append(out.Paths, v)
	}
	for _, row := range result.Trend {
		out.Trend = append(out.Trend, point{bgpRPKITrendPoint: row, ID: mcp.NativeRoleUUID(row.ID), Vantage: mcp.NativeRoleDigest(row.Vantage),
			Posture: verdict{row.Posture, mcp.NativeRoleDigest(row.Posture.ValidatorVersion)}})
	}
	return json.Marshal(out)
}
