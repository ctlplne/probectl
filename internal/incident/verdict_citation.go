// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package incident

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// SourceReference keeps original observation namespaces distinct. A path's
// opaque round ID is never relabelled as an entity-evidence UUID or an agent.
func (c VerdictCitation) SourceReference() (string, error) {
	if c.Routing != nil && c.SourceKind != "router_bgp" {
		return "", errors.New("routing reference on a different observation namespace")
	}
	if c.PeerASN != 0 || c.HandoffInterfaceID != "" {
		id, err := uuid.Parse(c.HandoffInterfaceID)
		if c.PeerASN == 0 || err != nil || id == uuid.Nil || id.String() != c.HandoffInterfaceID || (c.SourceKind == "control_plane_path" || c.SourceKind == "router_bgp") {
			return "", errors.New("invalid carrier handoff reference")
		}
	}
	switch c.SourceKind {
	case "", "entity_evidence":
		if c.EvidenceID != "" && c.PathRoundID == "" {
			return "entity_evidence:" + c.EvidenceID, nil
		}
	case "router_bgp":
		if c.EvidenceID != "" || c.PathRoundID != "" || c.Routing == nil || c.AgentID == "" {
			break
		}
		return c.routingSourceReference()
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

func (c VerdictCitation) routingSourceReference() (string, error) {
	r := c.Routing
	for _, value := range []string{r.ViewID, r.GenerationID} {
		id, err := uuid.Parse(value)
		if err != nil || id == uuid.Nil || id.String() != value {
			return "", errors.New("invalid original routing view")
		}
	}

	sequence, err := strconv.ParseInt(r.Sequence, 10, 64)
	digest, digestErr := hex.DecodeString(c.Digest)
	if err != nil || sequence <= 0 || strconv.FormatInt(sequence, 10) != r.Sequence || r.OriginASN == 0 || digestErr != nil || len(digest) != 32 || hex.EncodeToString(digest) != c.Digest || c.Digest == strings.Repeat("0", 64) {
		return "", errors.New("invalid selected-route identity")
	}
	if r.AddressesRedacted {
		if r.Address != "" || r.Prefix != "" {
			return "", errors.New("redacted routing reference contains addresses")
		}
	} else {
		prefix, err := netip.ParsePrefix(r.Prefix)
		if err != nil || prefix != prefix.Masked() || prefix.String() != r.Prefix || prefix.Bits() == 0 {
			return "", errors.New("invalid routing prefix")
		}
		address, err := netip.ParseAddr(r.Address)
		if err != nil || address.Zone() != "" || address.Unmap().String() != r.Address || !prefix.Contains(address) {
			return "", errors.New("invalid selected-route context")
		}
	}
	return "router_bgp:" + r.ViewID + ":" + r.GenerationID + ":" + r.Sequence + ":" + c.Digest, nil
}
