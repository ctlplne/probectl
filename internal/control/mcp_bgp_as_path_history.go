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
	"strconv"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
)

type mcpBGPASPathHistoryBackend struct{ server *Server }

func bgpASPathHistoryToolOption(server *Server) (mcp.Option, error) {
	schema, err := bgpHistoryToolSchema("/v1/bgp/visibility/{id}/paths", 7, "id")
	if err != nil {
		return nil, err
	}
	return mcp.WithBGPASPathHistoryBackend(mcpBGPASPathHistoryBackend{server}, schema), nil
}

func (b mcpBGPASPathHistoryBackend) BGPASPathHistory(ctx context.Context, actor *auth.Principal, command mcp.BGPASPathHistoryCommand) (json.RawMessage, error) {
	if b.server == nil || b.server.pool == nil || actor == nil || actor.UserID == "" {
		return nil, apierror.Forbidden("a current authorized tenant user is required")
	}
	limit := 100
	if command.Limit != nil {
		limit = *command.Limit
	}
	cursor, err := parseBGPASPathHistoryArgs(bgpASPathHistoryArgs{ID: command.ID, From: command.From, To: command.To,
		Source: command.Source, Vantage: command.Vantage, Cursor: command.Cursor, Limit: limit})
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
			return nil, apierror.Forbidden("AS path history tenant is inactive")
		}
		page, err := b.server.readBGPASPathHistory(ctx, actor, cursor, true)
		if err != nil {
			return nil, bgpASPathHistoryError(err)
		}
		return marshalNativeBGPASPathHistory(page)
	}
	body, err := read(ctx)
	if err != nil {
		return nil, err
	}
	if err := mcp.RetainNativePublication(ctx, func(active context.Context) error {
		if err := active.Err(); err != nil {
			return err
		}
		latest, err := read(active)
		if err != nil {
			return err
		}
		if !bytes.Equal(body, latest) {
			return apierror.Conflict("AS path history changed before publication")
		}
		return active.Err()
	}, func() {}); err != nil {
		return nil, err
	}
	return body, nil
}

type nativeASPathPublicSource struct {
	store.BGPASPathPublicSource
	BaselineSHA256    mcp.NativeRoleDigest   `json:"baseline_sha256"`
	ArchiveSHA256     mcp.NativeRoleDigest   `json:"archive_sha256"`
	ObservedUnixNanos mcp.NativeRoleRevision `json:"observed_unix_nanos"`
	RIBOriginatedAt   mcp.NativeRoleRevision `json:"rib_originated_unix_nanos,omitempty"`
}

func nativeBGPASPathSource(original *store.BGPASPathPublicSource) *nativeASPathPublicSource {
	if original == nil {
		return nil
	}
	value := &nativeASPathPublicSource{BGPASPathPublicSource: *original, BaselineSHA256: mcp.NativeRoleDigest(original.BaselineSHA256),
		ArchiveSHA256: mcp.NativeRoleDigest(original.ArchiveSHA256), ObservedUnixNanos: mcp.NativeRoleRevision(strconv.FormatInt(original.ObservedUnixNanos, 10))}
	if original.RIBOriginatedAt != nil {
		value.RIBOriginatedAt = mcp.NativeRoleRevision(strconv.FormatInt(*original.RIBOriginatedAt, 10))
	}
	return value
}

type nativeASPathStage struct {
	bgpASPathStage
	Sequence mcp.NativeRoleRevision    `json:"sequence,omitempty"`
	Original *nativeASPathPublicSource `json:"original,omitempty"`
}

func nativeBGPASPathStage(path *bgpASPathStage) *nativeASPathStage {
	if path == nil {
		return nil
	}
	value := &nativeASPathStage{bgpASPathStage: *path, Original: nativeBGPASPathSource(path.Original)}
	if path.Sequence != 0 {
		value.Sequence = mcp.NativeRoleRevision(strconv.FormatInt(path.Sequence, 10))
	}
	return value
}

func marshalNativeBGPASPathHistory(page bgpASPathHistoryPage) (json.RawMessage, error) {
	type monitor struct {
		store.BGPVisibilityMonitor
		ID mcp.NativeRoleUUID `json:"id"`
	}
	type incidentLink struct {
		store.BGPASPathIncident
		ID mcp.NativeRoleUUID `json:"id"`
	}
	type event struct {
		bgpASPathHistoryRow
		ID            mcp.NativeRoleUUID        `json:"id"`
		Vantage       mcp.NativeRoleDigest      `json:"vantage"`
		Sequence      mcp.NativeRoleRevision    `json:"sequence"`
		SourceEpoch   json.RawMessage           `json:"source_epoch"`
		ContextID     mcp.NativeRoleUUID        `json:"context_id,omitempty"`
		RouterID      mcp.NativeRoleUUID        `json:"router_id,omitempty"`
		ChangeEventID mcp.NativeRoleUUID        `json:"change_event_id,omitempty"`
		Previous      *nativeASPathStage        `json:"previous,omitempty"`
		Current       *nativeASPathStage        `json:"current,omitempty"`
		PublicSource  *nativeASPathPublicSource `json:"public_source,omitempty"`
		Incidents     []incidentLink            `json:"incidents,omitempty"`
	}
	out := struct {
		bgpASPathHistoryPage
		Monitor    monitor         `json:"monitor"`
		Items      []event         `json:"items"`
		NextCursor json.RawMessage `json:"next_cursor,omitempty"`
	}{bgpASPathHistoryPage: page, Monitor: monitor{page.Monitor, mcp.NativeRoleUUID(page.Monitor.ID)}, Items: []event{}}
	if page.NextCursor != "" {
		if _, err := parseBGPASPathHistoryArgs(bgpASPathHistoryArgs{ID: page.Monitor.ID, Cursor: page.NextCursor}); err != nil {
			return nil, err
		}
		cursor, err := nativeValidatedCursorJSON(page.NextCursor)
		if err != nil {
			return nil, err
		}
		out.NextCursor = cursor
	}
	for _, row := range page.Items {
		var epoch json.Marshaler = mcp.NativeRoleUUID(row.SourceEpoch)
		if row.SourceKind == "public_mrt" {
			epoch = mcp.NativeRoleDigest(row.SourceEpoch)
		}
		encoded, err := epoch.MarshalJSON()
		if err != nil {
			return nil, err
		}
		var incidents []incidentLink
		for _, link := range row.Incidents {
			incidents = append(incidents, incidentLink{link, mcp.NativeRoleUUID(link.ID)})
		}
		out.Items = append(out.Items, event{bgpASPathHistoryRow: row, ID: mcp.NativeRoleUUID(row.ID), Vantage: mcp.NativeRoleDigest(row.Vantage),
			Sequence: mcp.NativeRoleRevision(strconv.FormatInt(row.Sequence, 10)), SourceEpoch: encoded, ContextID: mcp.NativeRoleUUID(row.ContextID),
			RouterID: mcp.NativeRoleUUID(row.RouterID), ChangeEventID: mcp.NativeRoleUUID(row.ChangeEventID),
			Previous: nativeBGPASPathStage(row.Previous), Current: nativeBGPASPathStage(row.Current), PublicSource: nativeBGPASPathSource(row.PublicSource), Incidents: incidents})
	}
	return json.Marshal(out)
}
