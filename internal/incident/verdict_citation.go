// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package incident

import (
	"errors"

	"github.com/google/uuid"
)

// SourceReference keeps original observation namespaces distinct. A path's
// opaque round ID is never relabelled as an entity-evidence UUID or an agent.
func (c VerdictCitation) SourceReference() (string, error) {
	if c.PeerASN != 0 || c.HandoffInterfaceID != "" {
		id, err := uuid.Parse(c.HandoffInterfaceID)
		if c.PeerASN == 0 || err != nil || id == uuid.Nil || id.String() != c.HandoffInterfaceID || c.SourceKind == "control_plane_path" {
			return "", errors.New("invalid carrier handoff reference")
		}
	}
	switch c.SourceKind {
	case "", "entity_evidence":
		if c.EvidenceID != "" && c.PathRoundID == "" {
			return "entity_evidence:" + c.EvidenceID, nil
		}
	case "control_plane_path":
		if c.EvidenceID != "" || c.AgentID != "control_plane" || len(c.PathRoundID) != 32 {
			break
		}
		for _, ch := range c.PathRoundID {
			if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
				return "", errors.New("invalid original path round identifier")
			}
		}
		return "control_plane_path:" + c.PathRoundID, nil
	}
	return "", errors.New("invalid verdict observation namespace")
}
