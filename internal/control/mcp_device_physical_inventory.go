// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
)

func devicePhysicalInventoryToolOption(server *Server) (mcp.Option, error) {
	schema, err := bgpHistoryToolSchema("/v1/device/physical-inventory", 6, "context_id", "device_entity_id", "agent_id", "source_ref")
	if err != nil {
		return nil, err
	}
	backend := nativeCanonicalDeviceBackend{server}
	return mcp.WithDevicePhysicalInventoryBackend(schema, func(ctx context.Context, actor *auth.Principal,
		command mcp.DevicePhysicalInventoryCommand) (json.RawMessage, error) {
		query := url.Values{"context_id": {command.ContextID}, "device_entity_id": {command.DeviceEntityID},
			"agent_id": {command.AgentID}, "source_ref": {command.SourceRef}, "observation_id": {command.ObservationID}}
		if command.AfterIndex != nil {
			query.Set("after_index", strconv.FormatUint(uint64(*command.AfterIndex), 10))
		}
		selected, err := parseDevicePhysicalInventorySelection(query)
		if err != nil {
			return nil, err
		}
		return backend.publishRead(ctx, actor, func(active context.Context) (json.RawMessage, error) {
			page, err := server.readDevicePhysicalInventory(active, actor, selected)
			if err != nil {
				return nil, err
			}
			// Preserve the server-generated page identity through MCP redaction.
			// All collected component strings still pass through the redactor.
			return json.Marshal(struct {
				devicePhysicalInventoryPage
				ObservationID mcp.NativeRoleUUID `json:"observation_id"`
			}{page, mcp.NativeRoleUUID(page.ObservationID)})
		})
	}), nil
}
