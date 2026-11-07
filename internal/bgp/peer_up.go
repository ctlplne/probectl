// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
)

// PeerUpInformation retains an opaque TLV in the Peer Up namespace. It must
// not be interpreted as an Initiation TLV or as tenant/router authorization.
type PeerUpInformation struct {
	Type  uint16
	Value []byte
}

// PeerUp is an owned copy of complete source metadata, not a live-session
// credential. Repeated information TLVs retain their order and values.
type PeerUp struct {
	SourceProfile          RoutingSourceProfile
	Header                 BMPRouteViewHeader
	LocalAddress           netip.Addr
	LocalPort, RemotePort  uint16
	SentOpen, ReceivedOpen []byte
	Information            []PeerUpInformation
}

// PeerMessageBudget bounds the whole operation before capability maps or output
// allocation. MemoryBytes conservatively charges 128 bytes per input byte,
// including complete OPEN parsing and copied TLV descriptors/values. WorkUnits
// charges four byte passes. There is no independent TLV/population ceiling.
type PeerMessageBudget struct{ MemoryBytes, WorkUnits int64 }

var (
	ErrBMPPeerUp       = errors.New("bgp: malformed or inconsistent peer-up frame")
	ErrBMPPeerUpBudget = errors.New("bgp: peer-up operation admission exceeded")
)

// parseBMPPeerUp decodes one complete RFC7854/RFC9069 Peer Up frame. Both OPENs
// and every information tail must validate before any metadata is returned.
// Authentication, canonical ownership, revocation and session epoch fencing
// belong to the listener/store; a payload address cannot establish them.
func parseBMPPeerUp(ctx context.Context, raw []byte, budget PeerMessageBudget, profiles ...RoutingSourceProfile) (PeerUp, error) {
	none := PeerUp{}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	profile, err := routingSourceProfile(profiles)
	if err != nil {
		return none, err
	}
	if budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 || int64(len(raw)) > budget.MemoryBytes/128 || int64(len(raw)) > budget.WorkUnits/4 {
		return none, ErrBMPPeerUpBudget
	}
	const bodyOffset = bmpCommonHeaderLen + bmpPeerHeaderLen
	if len(raw) < bodyOffset+20 || raw[0] != bmpVersion || raw[5] != 3 || uint64(binary.BigEndian.Uint32(raw[1:5])) != uint64(len(raw)) {
		return none, ErrBMPPeerUp
	}
	header, err := ParseBMPRouteViewHeader(raw[bmpCommonHeaderLen:bodyOffset])
	if err != nil {
		return none, ErrBMPPeerUp
	}
	if profile.Format != "" && header.View != BMPLocRIB {
		return none, ErrBMPPeerUp
	}
	local := raw[bodyOffset : bodyOffset+16]
	localPort := binary.BigEndian.Uint16(raw[bodyOffset+16 : bodyOffset+18])
	remotePort := binary.BigEndian.Uint16(raw[bodyOffset+18 : bodyOffset+20])
	var address netip.Addr
	switch {
	case header.View == BMPLocRIB:
		if !bytes.Equal(local, make([]byte, 16)) || localPort != 0 || remotePort != 0 {
			return none, ErrBMPPeerUp
		}
	case header.Flags&0x80 != 0:
		address = netip.AddrFrom16([16]byte(local))
	default:
		if !bytes.Equal(local[:12], make([]byte, 12)) {
			return none, ErrBMPPeerUp
		}
		address = netip.AddrFrom4([4]byte(local[12:]))
	}
	sent, rest, err := takeRouteOpen(raw[bodyOffset+20:], profile)
	if err != nil {
		return none, err
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	received, info, err := takeRouteOpen(rest, profile)
	if err != nil {
		return none, err
	}
	if header.View == BMPLocRIB {
		capabilities, err := parseRouteOpenCapabilities(sent, profile)
		if err != nil || !capabilities.fourAS || !bytes.Equal(sent, received) {
			return none, ErrBMPPeerUp
		}
	}
	count := 0
	for offset := 0; offset < len(info); {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		if len(info)-offset < 4 {
			return none, ErrBMPPeerUp
		}
		length := int(binary.BigEndian.Uint16(info[offset+2 : offset+4]))
		offset += 4
		if length > len(info)-offset {
			return none, ErrBMPPeerUp
		}
		offset += length
		count++
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	out := PeerUp{Header: header, SourceProfile: profile, LocalAddress: address, LocalPort: localPort, RemotePort: remotePort,
		SentOpen: append([]byte(nil), sent...), ReceivedOpen: append([]byte(nil), received...),
		Information: make([]PeerUpInformation, 0, count)}
	for offset := 0; offset < len(info); {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		kind, length := binary.BigEndian.Uint16(info[offset:offset+2]), int(binary.BigEndian.Uint16(info[offset+2:offset+4]))
		offset += 4
		out.Information = append(out.Information, PeerUpInformation{Type: kind, Value: append([]byte(nil), info[offset:offset+length]...)})
		offset += length
	}
	return out, nil
}

func takeRouteOpen(raw []byte, profile RoutingSourceProfile) ([]byte, []byte, error) {
	if len(raw) < bgpHeaderLen {
		return nil, nil, ErrBMPPeerUp
	}
	length := int(binary.BigEndian.Uint16(raw[16:18]))
	if length < 29 || length > len(raw) {
		return nil, nil, ErrBMPPeerUp
	}
	if _, err := parseRouteOpenCapabilities(raw[:length], profile); err != nil {
		return nil, nil, errors.Join(ErrBMPPeerUp, err)
	}
	return raw[:length], raw[length:], nil
}

// DecodeRoutingPeerUp validates the complete metadata used to start private
// routing generations. It grants no tenant/router/session authority. Only
// supported unicast families declared by both complete OPENs are staged.
func DecodeRoutingPeerUp(ctx context.Context, raw []byte, budget PeerMessageBudget, profiles ...RoutingSourceProfile) (PeerUp, []RouteFamily, error) {
	peer, err := parseBMPPeerUp(ctx, raw, budget, profiles...)
	if err != nil {
		return PeerUp{}, nil, err
	}
	sent, err := parseRouteOpenCapabilities(peer.SentOpen, peer.SourceProfile)
	if err != nil {
		return PeerUp{}, nil, err
	}
	received, err := parseRouteOpenCapabilities(peer.ReceivedOpen, peer.SourceProfile)
	if err != nil {
		return PeerUp{}, nil, err
	}
	var families []RouteFamily
	for _, family := range []RouteFamily{{AFI: 1, SAFI: 1}, {AFI: 2, SAFI: 1}} {
		if sent.families[family] && received.families[family] {
			families = append(families, family)
		}
	}
	if err := ctx.Err(); err != nil {
		return PeerUp{}, nil, err
	}
	if len(families) == 0 {
		return PeerUp{}, nil, ErrRouteCapabilities
	}
	return peer, families, nil
}
