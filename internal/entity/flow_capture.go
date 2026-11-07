// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"encoding/json"
	"net/netip"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
)

// FlowCaptureInput contains observed dimensions, never canonical ownership.
// The raw-record digest covers every original field; this tuple separately
// binds the fields used for routing so an authenticated sender cannot attest
// another source's digest with a different, authorized lookup tuple.
type FlowCaptureInput struct {
	Exporter, Source, Destination netip.Addr
	Protocol                      string
	Domain                        uint32
}

// FlowCaptureKey is an identifier, not a reader grant. The evidence writer
// passes tenant/agent from its verified peer. A bus consumer may use claimed
// agent identity only to look up this independently authenticated witness;
// the claim itself can never create a positive canonical capture.
func FlowCaptureKey(tenant, sender string, rawDigest [32]byte, input FlowCaptureInput) ([32]byte, error) {
	tenantID, err := uuid.Parse(tenant)
	if err != nil || tenantID == uuid.Nil || tenantID.String() != tenant || rawDigest == ([32]byte{}) {
		return [32]byte{}, ErrInvalidClaim
	}
	input.Exporter, input.Source, input.Destination = input.Exporter.Unmap(), input.Source.Unmap(), input.Destination.Unmap()
	if !input.Exporter.IsValid() || input.Exporter.Zone() != "" || input.Exporter.IsUnspecified() || input.Exporter.IsMulticast() || !input.Source.IsValid() || input.Source.Zone() != "" || !input.Destination.IsValid() || input.Destination.Zone() != "" {
		return [32]byte{}, ErrInvalidClaim
	}
	key := SourceKey{AgentID: sender, Kind: FlowExporter, SourceRef: input.Exporter.String()}
	if normalized, err := key.Normalize(); err != nil || normalized != key {
		return [32]byte{}, ErrInvalidClaim
	}
	switch input.Protocol {
	case "netflow5", "netflow9", "ipfix", "sflow5":
	default:
		return [32]byte{}, ErrInvalidClaim
	}
	body, err := json.Marshal(struct {
		Version, Tenant, Sender string
		RawDigest               [32]byte
		Input                   FlowCaptureInput
	}{"flow_capture_v1", tenant, sender, rawDigest, input})
	if err != nil {
		return [32]byte{}, err
	}
	digest := crypto.Hash(body)
	if len(digest) != 32 {
		return [32]byte{}, ErrInvalidClaim
	}
	var result [32]byte
	copy(result[:], digest)
	return result, nil
}
