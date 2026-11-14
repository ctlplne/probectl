// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
)

var ErrConfigBinding = errors.New("device config archive requires a complete owned context/device/source binding")

// ConfigArchiveBinding is an operator assertion about the existing archive's
// canonical device. It is not a receipt that a collector read the content.
// Assignment epochs and BoundAt are stamped by the store, never by the input.
type ConfigArchiveBinding struct {
	Kind             string    `json:"kind"`
	ContextID        string    `json:"context_id"`
	DeviceEntityID   string    `json:"device_entity_id"`
	AgentID          string    `json:"agent_id"`
	SourceRef        string    `json:"source_ref"`
	SourceAssignedAt time.Time `json:"source_assigned_at"`
	AgentAssignedAt  time.Time `json:"agent_assigned_at"`
	BoundAt          time.Time `json:"bound_at"`
}

func normalizeConfigBinding(tenant string, input *ConfigArchiveBinding) (*ConfigArchiveBinding, error) {
	if input == nil {
		return nil, nil
	}
	scope, err := (entity.Scope{TenantID: tenant, ContextID: input.ContextID}).Normalize()
	if err != nil || scope.ContextID != input.ContextID || scope.TenantID != tenant {
		return nil, ErrConfigBinding
	}
	id, err := uuid.Parse(input.DeviceEntityID)
	if err != nil || id == uuid.Nil || id.String() != input.DeviceEntityID {
		return nil, ErrConfigBinding
	}
	source, err := (entity.SourceKey{AgentID: input.AgentID, Kind: entity.DeviceTarget, SourceRef: input.SourceRef}).Normalize()
	if err != nil || source.AgentID != input.AgentID || source.SourceRef != input.SourceRef {
		return nil, ErrConfigBinding
	}
	return &ConfigArchiveBinding{Kind: "operator_bound_archive", ContextID: scope.ContextID, DeviceEntityID: id.String(), AgentID: source.AgentID, SourceRef: source.SourceRef}, nil
}
