// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

// BMPRouteView distinguishes what the router reported. Adjacent routing views
// are not evidence of the router's selected Loc-RIB or its forwarding table.
type BMPRouteView string

const (
	BMPAdjRIBInPrePolicy   BMPRouteView = "adj_rib_in_pre_policy"
	BMPAdjRIBInPostPolicy  BMPRouteView = "adj_rib_in_post_policy"
	BMPAdjRIBOutPrePolicy  BMPRouteView = "adj_rib_out_pre_policy"
	BMPAdjRIBOutPostPolicy BMPRouteView = "adj_rib_out_post_policy"
	BMPLocRIB              BMPRouteView = "loc_rib"
)

// BMPRouteViewHeader is untrusted protocol metadata, never tenant/context/router
// authorization. Distinguisher/BGPIdentifier/peer address must be matched to the
// authenticated, currently owned source before any route state can be selected.
// Filtered and missing timestamps cannot become complete/current by default.
type BMPRouteViewHeader struct {
	PeerType, Flags byte
	Distinguisher   [8]byte
	PeerAddress     netip.Addr // not applicable for Loc-RIB, so remains invalid
	PeerASN         uint32
	BGPIdentifier   netip.Addr
	View            BMPRouteView
	ASNWidth        int
	Filtered        bool
	Timestamp       time.Time
	TimestampKnown  bool
}

var ErrBMPRouteViewHeader = errors.New("bgp: invalid or unsupported route-view peer header")

// ParseBMPRouteViewHeader reads the fixed42-byte RFC7854 peer header. RFC8671
// defines Adj-RIB-Out; RFC9069 defines a separate Loc-RIB flag namespace and
// four-octet ASN encoding. It does not activate ingestion or infer ownership.
func ParseBMPRouteViewHeader(raw []byte) (BMPRouteViewHeader, error) {
	none := BMPRouteViewHeader{}
	if len(raw) != bmpPeerHeaderLen || raw[0] > 3 {
		return none, ErrBMPRouteViewHeader
	}
	seconds, micros := binary.BigEndian.Uint32(raw[34:38]), binary.BigEndian.Uint32(raw[38:42])
	if micros >= 1000000 {
		return none, ErrBMPRouteViewHeader
	}
	out := BMPRouteViewHeader{PeerType: raw[0], Flags: raw[1], PeerASN: binary.BigEndian.Uint32(raw[26:30]), BGPIdentifier: netip.AddrFrom4([4]byte(raw[30:34])), ASNWidth: 4}
	copy(out.Distinguisher[:], raw[2:10])
	if seconds != 0 || micros != 0 {
		out.Timestamp = time.Unix(int64(seconds), int64(micros)*1000).UTC()
		out.TimestampKnown = true
	}
	if out.PeerType == 3 {
		// The Loc-RIB address is not a remote peer address. Its F bit is
		// neither the adjacent-view V bit nor permission to guess a family.
		for _, b := range raw[10:26] {
			if b != 0 {
				return none, ErrBMPRouteViewHeader
			}
		}
		out.View = BMPLocRIB
		out.Filtered = out.Flags&0x80 != 0
		return out, nil
	}
	if out.PeerType == 0 && out.Distinguisher != [8]byte{} {
		return none, ErrBMPRouteViewHeader
	}
	if out.Flags&0x80 != 0 {
		out.PeerAddress = netip.AddrFrom16([16]byte(raw[10:26]))
	} else {
		for _, b := range raw[10:22] {
			if b != 0 {
				return none, ErrBMPRouteViewHeader
			}
		}
		out.PeerAddress = netip.AddrFrom4([4]byte(raw[22:26]))
	}
	if out.Flags&0x20 != 0 {
		out.ASNWidth = 2
	}
	switch out.Flags & 0x50 {
	case 0:
		out.View = BMPAdjRIBInPrePolicy
	case 0x40:
		out.View = BMPAdjRIBInPostPolicy
	case 0x10:
		out.View = BMPAdjRIBOutPrePolicy
	case 0x50:
		out.View = BMPAdjRIBOutPostPolicy
	}
	return out, nil
}
