// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"errors"
	"strings"
	"unicode"
)

var ErrInvalidSource = errors.New("entity: invalid authenticated source key")

// SourceKind names an existing, operator-configured producer family. The
// agent ID comes from authenticated transport or server registration; a raw
// packet may only supply observational evidence, never this key's authority.
type SourceKind string

const (
	DeviceTarget SourceKind = "device_target"
	FlowExporter SourceKind = "flow_exporter"
	PathAgent    SourceKind = "path_agent"
	BMPPeer      SourceKind = "bmp_peer"
	AgentSite    SourceKind = "agent_site"
)

type SourceKey struct {
	AgentID   string     `json:"agent_id"`
	Kind      SourceKind `json:"source_kind"`
	SourceRef string     `json:"source_ref"`
}

func (s SourceKey) Normalize() (SourceKey, error) {
	s.AgentID = strings.TrimSpace(s.AgentID)
	s.SourceRef = strings.TrimSpace(s.SourceRef)
	if s.AgentID == "" || len(s.AgentID) > 128 || s.SourceRef == "" || len(s.SourceRef) > 1024 ||
		strings.IndexFunc(s.AgentID, unicode.IsControl) >= 0 ||
		strings.IndexFunc(s.SourceRef, unicode.IsControl) >= 0 {
		return SourceKey{}, ErrInvalidSource
	}
	switch s.Kind {
	case DeviceTarget, FlowExporter, PathAgent, BMPPeer, AgentSite:
		return s, nil
	default:
		return SourceKey{}, ErrInvalidSource
	}
}
