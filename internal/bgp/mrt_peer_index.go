// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
)

var (
	ErrMRTRecord = errors.New("bgp: malformed or unsupported MRT source record")
	ErrMRTBudget = errors.New("bgp: complete MRT source record exceeds operation admission")
)

// MRTPeerIndex preserves the complete RFC6396 source table in original order.
// It proves framing only: neither its identifiers nor its clock grant tenant
// authority, a selected router view, or whole-file completeness.
type MRTPeerIndex struct {
	ObservedUnixNanos   int64
	CollectorIdentifier uint32
	ViewName            []byte
	Peers               []MRTIndexPeer
}

type MRTIndexPeer struct {
	Address            netip.Addr
	ASN, BGPIdentifier uint32
}

// DecodeMRTPeerIndex validates the complete raw MRT record before returning
// owned peer metadata. Finite byte/work admission covers the entire table; the
// only peer/view length fields are the original uint16 wire representation.
func DecodeMRTPeerIndex(ctx context.Context, raw []byte, budget UpdateFrameBudget) (MRTPeerIndex, error) {
	timestamp, subtype, body, err := decodeMRTTableRecord(ctx, raw, budget)
	if err != nil {
		return MRTPeerIndex{}, err
	}
	if subtype != 1 || len(body) < 8 {
		return MRTPeerIndex{}, ErrMRTRecord
	}
	viewLength := int(binary.BigEndian.Uint16(body[4:6]))
	if viewLength > len(body)-8 {
		return MRTPeerIndex{}, ErrMRTRecord
	}
	count := int(binary.BigEndian.Uint16(body[6+viewLength : 8+viewLength]))
	peerBytes := body[8+viewLength:]
	// Every peer consumes at least eleven bytes. Refuse a declared population
	// before allocating it, and validate every late entry and trailing byte.
	if count > len(peerBytes)/11 {
		return MRTPeerIndex{}, ErrMRTRecord
	}
	if _, err := decodeMRTIndexPeers(ctx, peerBytes, count, false); err != nil {
		return MRTPeerIndex{}, err
	}
	peers, err := decodeMRTIndexPeers(ctx, peerBytes, count, true)
	if err != nil {
		return MRTPeerIndex{}, err
	}
	return MRTPeerIndex{ObservedUnixNanos: timestamp, CollectorIdentifier: binary.BigEndian.Uint32(body[:4]), ViewName: append([]byte{}, body[6:6+viewLength]...), Peers: peers}, nil
}

func decodeMRTTableRecord(ctx context.Context, raw []byte, budget UpdateFrameBudget) (int64, uint16, []byte, error) {
	if err := ctx.Err(); err != nil {
		return 0, 0, nil, err
	}
	if budget.MemoryBytes <= 4096 || budget.WorkUnits <= 4096 || int64(len(raw)) > (budget.MemoryBytes-4096)/128 || int64(len(raw)) > (budget.WorkUnits-4096)/16 {
		return 0, 0, nil, ErrMRTBudget
	}
	if len(raw) < 12 || binary.BigEndian.Uint16(raw[4:6]) != 13 || uint64(binary.BigEndian.Uint32(raw[8:12])) != uint64(len(raw)-12) {
		return 0, 0, nil, ErrMRTRecord
	}
	return int64(binary.BigEndian.Uint32(raw[:4])) * 1_000_000_000, binary.BigEndian.Uint16(raw[6:8]), raw[12:], nil
}

func decodeMRTIndexPeers(ctx context.Context, raw []byte, count int, retain bool) ([]MRTIndexPeer, error) {
	var peers []MRTIndexPeer
	if retain {
		peers = make([]MRTIndexPeer, 0, count)
	}
	for range count {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(raw) < 5 || raw[0]&^byte(3) != 0 {
			return nil, ErrMRTRecord
		}
		addressBytes, asnBytes := 4, 2
		if raw[0]&1 != 0 {
			addressBytes = 16
		}
		if raw[0]&2 != 0 {
			asnBytes = 4
		}
		size := 5 + addressBytes + asnBytes
		if len(raw) < size {
			return nil, ErrMRTRecord
		}
		if retain {
			peer := MRTIndexPeer{BGPIdentifier: binary.BigEndian.Uint32(raw[1:5])}
			peer.Address, _ = netip.AddrFromSlice(raw[5 : 5+addressBytes])
			if asnBytes == 4 {
				peer.ASN = binary.BigEndian.Uint32(raw[5+addressBytes : size])
			} else {
				peer.ASN = uint32(binary.BigEndian.Uint16(raw[5+addressBytes : size]))
			}
			peers = append(peers, peer)
		}
		raw = raw[size:]
	}
	if len(raw) != 0 {
		return nil, ErrMRTRecord
	}
	return peers, nil
}
