// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"encoding/hex"
	"net/netip"
	"time"
)

// BMPObservationPeer describes a protocol observation and its optional original
// router clock. Authority always comes from the authenticated source.
type BMPObservationPeer struct {
	PeerType      uint8        `json:"peer_type"`
	Flags         uint8        `json:"flags"`
	Distinguisher string       `json:"distinguisher,omitempty"`
	PeerAddress   netip.Addr   `json:"peer_address,omitzero"`
	PeerASN       uint32       `json:"peer_asn"`
	BGPIdentifier netip.Addr   `json:"bgp_identifier"`
	View          BMPRouteView `json:"view"`
	Filtered      bool         `json:"filtered"`
	OriginalClock *time.Time   `json:"original_clock,omitempty"`
}

func observeBMPPeer(header BMPRouteViewHeader) BMPObservationPeer {
	value := BMPObservationPeer{PeerType: header.PeerType, Flags: header.Flags, PeerAddress: header.PeerAddress.Unmap(),
		PeerASN: header.PeerASN, BGPIdentifier: header.BGPIdentifier, View: header.View, Filtered: header.Filtered}
	if header.Distinguisher != ([8]byte{}) {
		value.Distinguisher = hex.EncodeToString(header.Distinguisher[:])
	}
	if header.TimestampKnown {
		value.OriginalClock = &header.Timestamp
	}
	return value
}
