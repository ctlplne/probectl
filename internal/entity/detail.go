// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import "time"

// EvidenceRecord keeps a source's original identifier and observation even
// after its current operator mapping changes. Current is derived on each read
// from the live tenant/context assignment; history is never silently merged.
type EvidenceRecord struct {
	ID                   string     `json:"id"`
	ObservationID        string     `json:"observation_id"`
	Alias                AliasKey   `json:"alias"`
	Source               string     `json:"source"`
	SourceRef            string     `json:"source_ref"`
	SourceKey            SourceKey  `json:"source_key"`
	SupportEvidenceID    string     `json:"support_evidence_id,omitempty"`
	OriginSerial         string     `json:"origin_serial,omitempty"`
	InterfaceName        string     `json:"interface_name,omitempty"`
	InterfaceDescription string     `json:"interface_description,omitempty"`
	NeighborProtocol     string     `json:"neighbor_protocol,omitempty"`
	NeighborLocalIfIndex uint32     `json:"neighbor_local_if_index,omitempty"`
	NeighborLocalPortID  string     `json:"neighbor_local_port_id,omitempty"`
	NeighborRemotePortID string     `json:"neighbor_remote_port_id,omitempty"`
	NeighborChassisID    string     `json:"neighbor_chassis_id,omitempty"`
	NeighborDeviceName   string     `json:"neighbor_device_name,omitempty"`
	NeighborAddress      string     `json:"neighbor_management_address,omitempty"`
	ObservedAt           time.Time  `json:"observed_at"`
	ExpiresAt            *time.Time `json:"expires_at,omitempty"`
	Current              bool       `json:"current"`
}

type EvidencePage struct {
	Scope      Scope            `json:"scope"`
	EntityID   string           `json:"entity_id"`
	Items      []EvidenceRecord `json:"items"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

// LinkRecord is one typed, evidence-backed relationship. SourceKind allows
// each user surface to enforce that plane's read permission before exposure.
type LinkRecord struct {
	ID           string     `json:"id"`
	FromEntityID string     `json:"from_entity_id"`
	ToEntityID   string     `json:"to_entity_id"`
	EvidenceID   string     `json:"evidence_id"`
	Kind         string     `json:"kind"`
	SourceKind   SourceKind `json:"source_kind"`
	ObservedAt   time.Time  `json:"observed_at"`
}

type LinkPage struct {
	Scope      Scope        `json:"scope"`
	EntityID   string       `json:"entity_id"`
	Items      []LinkRecord `json:"items"`
	NextCursor string       `json:"next_cursor,omitempty"`
}
